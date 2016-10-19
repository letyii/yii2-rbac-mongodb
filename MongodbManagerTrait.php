<?php

namespace letyii\rbacmongodb;

use yii\helpers\ArrayHelper;
use yii\mongodb\Query;
use yii\rbac\Assignment;
use yii\rbac\Item;

/**
 * Class MongoManagerTrait
 * @property mixed $db
 * @property mixed $itemTable
 * @property mixed $itemChildTable
 * @property mixed $assignmentTable
 * @property mixed $ruleTable
 * @property mixed $god_id
 * @package letyii\rbacmongodb
 */
trait MongodbManagerTrait
{
	/**
	 * @param $parentName
	 * @param $removeChild
	 * @return mixed
	 */
	abstract public function removeChild($parentName, $removeChild);

	/**
	 * @param $parent
	 * @param $child
	 * @return mixed
	 */
	abstract protected function detectLoop($parent, $child);

	/**
	 * @param $name
	 * @return mixed
	 */
	abstract protected function getItem($name);

	/**
	 * @return mixed
	 */
	abstract public function getRoles();

	/**
	 * @param $parent
	 * @param null $type
	 * @return bool
	 */
	public function removeChildrenByType($parent, $type = null)
	{
		if (empty($type))
			return false;

		$parentName = is_object($parent) ? $parent->name : $parent;

		// Get all children, included role and permission
		$children = (new Query)
			->select(['child'])
			->from($this->itemChildTable)
			->where(['parent' => $parentName])
			->all($this->db);
		if ($children)
			$children = ArrayHelper::map($children, '_id', 'child');
		else
			$children = [];

		// Get all items by type
		$items = (new Query)
			->select(['name'])
			->from($this->itemTable)
			->where(['type' => $type])
			->all($this->db);

		$removeChildren = [];
		foreach ($items as $item) {
			if (in_array($item['name'], $children)) {
				$removeChildren[] = $item['name'];
			}
		}

		// Delete all child in parent
		foreach ($removeChildren as $removeChild) {
			$this->removeChild($parentName, $removeChild);
		}

		return true;
	}

	/**
	 * Public wrapper for detectLoop function
	 * @param Item $parent the parent item
	 * @param Item $child the child item to be added to the hierarchy
	 * @return boolean whether a loop exists
	 */
	public function canAddChild($parent, $child)
	{
		return !$this->detectLoop($parent, $child);
	}

	/**
	 * @param $name
	 * @return bool
	 */
	public function checkItemExist($name)
	{
		if ($this->getItem($name) === null)
			return false;
		else
			return true;
	}

	/**
	 * Return all user assignment information for the specified role
	 * @param string $roleName the role name
	 * @return array The assignment information. An empty array will be returned if there is no user assigned to the role.
	 */
	public function getRoleAssignments($roleName)
	{
		$query = (new Query)->from($this->assignmentTable)
			->where(['item_name' => $roleName]);

		$assignments = [];
		foreach ($query->all($this->db) as $row) {
			$assignments[$row['user_id']] = new Assignment([
				'userId' => $row['user_id'],
				'roleName' => $row['item_name'],
				'createdAt' => $row['created_at'],
			]);
		}

		return $assignments;
	}

	/**
	 * Build tree from item table
	 * @param string|bool $item_name
	 * @param array $roleList
	 * @return array
	 */
	public function buildTreeRole($item_name = null, $roleList = [])
	{
		$tree = [];
		$allParents = [];
		if (empty($roleList))
			$roleList = $this->getRoles();

		if ($item_name == null) {
			// Get all children
			$childRoles = [];
			$query = (new Query)->select(['child'])
				->from($this->itemChildTable)
				->where([]);
			foreach ($query->all($this->db) as $key => $value) {
				$childRoles[] = $value['child'];
			}

			// Get all roles
			$query = (new Query)->select(['name'])
				->from($this->itemTable)
				->where(['type' => 1]);
			foreach ($query->all($this->db) as $key => $value) {
				if (!in_array($value['name'], $childRoles))
					$allParents[] = $value;
			}
		}
		if (!empty($allParents)) {
			foreach ($allParents as $parent) {
				$tree[$parent['name']] = [
					'title' => $roleList[$parent['name']]->description,
					'items' => $this->buildTreeRole($parent['name'], $roleList),
				];
			}
		} else {
			// Get
			$childs = (new Query)->select(['child'])
				->from($this->itemChildTable)
				->where(['parent' => $item_name])
				->all($this->db);

			// lấy ra name của các role gán vào mảng mới.
			$checkRole = [];
			foreach ($roleList as $v) {
				$checkRole[] = $v->name;
			}

			foreach ($childs as $child) {
				// Nếu item là permission thì bỏ qua.
				if (!in_array($child['child'], $checkRole))
					continue;
				$tree[$child['child']] = [
					'title' => $roleList[$child['child']]->description,
					'items' => $this->buildTreeRole($child['child'], $roleList),
				];
			}
		}

		return $tree;
	}
}